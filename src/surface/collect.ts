/// <reference lib="dom" />
/**
 * The function that runs inside the page. It is serialized by the browser
 * driver, so it must be self-contained: no imports, no closures, no helpers
 * defined outside its body.
 */
import type { HiddenBy, SurfaceSnapshot } from "./types.ts";

export type CollectedSurface = Pick<SurfaceSnapshot, "blocks" | "attributes" | "scripts" | "storage" | "selectorMatches">;

export interface CollectArgs {
  absentSelectors: string[];
  maxBlocks: number;
  maxText: number;
}

export function collectSurface(args: CollectArgs): CollectedSurface {
  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "HEAD", "TITLE", "META", "LINK"]);
  const clip = (text: string): string => (text.length > args.maxText ? `${text.slice(0, args.maxText)}…` : text);
  const norm = (text: string): string => text.replace(/\s+/g, " ").trim();

  const selectorOf = (element: Element): string => {
    const parts: string[] = [];
    let node: Element | null = element;
    while (node !== null && parts.length < 5) {
      if (node.id !== "" && /^[A-Za-z][\w-]*$/.test(node.id)) {
        parts.unshift(`#${node.id}`);
        break;
      }
      let part = node.tagName.toLowerCase();
      const parent: Element | null = node.parentElement;
      if (parent !== null) {
        const same = Array.from(parent.children).filter((child) => child.tagName === node!.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(node) + 1})`;
      }
      parts.unshift(part);
      node = parent;
    }
    return parts.join(" > ");
  };

  const blurPx = (filter: string): number => {
    const match = /blur\(([\d.]+)px\)/.exec(filter);
    return match === null ? 0 : Number(match[1]);
  };
  const alphaOf = (color: string): number => {
    if (color === "transparent") return 0;
    const match = /rgba?\(([^)]+)\)/.exec(color);
    if (match === null) return 1;
    const parts = match[1]!.split(/[ ,/]+/).filter((part) => part.length > 0);
    return parts.length >= 4 ? Number(parts[3]) : 1;
  };

  const hiddenBy = (element: Element): HiddenBy | null => {
    const checkable = element as Element & { checkVisibility?: (options: Record<string, boolean>) => boolean };
    const rect = element.getBoundingClientRect();
    for (let node: Element | null = element; node !== null; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === "none") return "display";
      if (blurPx(style.filter) >= 2) return "blur";
      if (Number(style.opacity) < 0.1) return "opacity";
      if (node !== element && style.overflow !== "visible" && style.overflow !== "") {
        const box = node.getBoundingClientRect();
        const outside = rect.bottom <= box.top || rect.top >= box.bottom || rect.right <= box.left || rect.left >= box.right;
        if (outside || box.width < 2 || box.height < 2) return "clipped";
      }
    }
    if (checkable.checkVisibility !== undefined && !checkable.checkVisibility({ checkVisibilityCSS: true, visibilityProperty: true, contentVisibilityAuto: true })) {
      return "visibility";
    }
    const style = getComputedStyle(element);
    if (style.visibility !== "visible") return "visibility";
    if (alphaOf(style.color) < 0.1) return style.textShadow !== "none" ? "blur" : "transparent-text";
    if (rect.width === 0 || rect.height === 0) return "zero-size";
    if (style.clip !== "auto" && style.clip !== "" && (rect.width <= 1 || rect.height <= 1)) return "clipped";
    return null;
  };

  const blocks: CollectedSurface["blocks"] = [];
  const attributes: CollectedSurface["attributes"] = [];
  const scripts: CollectedSurface["scripts"] = [];

  for (const element of Array.from(document.querySelectorAll("body *"))) {
    if (SKIP.has(element.tagName)) {
      if (element.tagName === "SCRIPT" && !(element as HTMLScriptElement).src) {
        const text = norm(element.textContent ?? "");
        if (text.length > 0) scripts.push({ selector: selectorOf(element), text });
      }
      continue;
    }
    for (const attribute of Array.from(element.attributes)) {
      const isValue = attribute.name === "value" && element.tagName === "INPUT";
      if ((attribute.name.startsWith("data-") || isValue) && attribute.value.trim().length > 0) {
        attributes.push({ selector: selectorOf(element), name: attribute.name, value: clip(norm(attribute.value)) });
      }
    }
    if (blocks.length >= args.maxBlocks) continue;
    let own = "";
    for (const child of Array.from(element.childNodes)) if (child.nodeType === 3) own += ` ${child.textContent ?? ""}`;
    own = norm(own);
    if (own.length === 0) continue;
    blocks.push({ selector: selectorOf(element), text: clip(own), hiddenBy: hiddenBy(element) });
  }
  for (const script of Array.from(document.querySelectorAll("head script:not([src])"))) {
    const text = norm(script.textContent ?? "");
    if (text.length > 0) scripts.push({ selector: selectorOf(script), text });
  }

  const storage: CollectedSurface["storage"] = [];
  for (const area of ["localStorage", "sessionStorage"] as const) {
    try {
      const store = window[area];
      for (let i = 0; i < store.length; i += 1) {
        const key = store.key(i);
        if (key !== null) storage.push({ area, key, value: clip(store.getItem(key) ?? "") });
      }
    } catch {
      // Storage can be blocked for the origin; nothing to record.
    }
  }

  const selectorMatches: CollectedSurface["selectorMatches"] = [];
  for (const selector of args.absentSelectors) {
    try {
      const found = document.querySelector(selector);
      if (found !== null) selectorMatches.push({ selector, text: clip(norm(found.textContent ?? "")) });
    } catch {
      selectorMatches.push({ selector, text: "(invalid selector)" });
    }
  }

  return { blocks, attributes, scripts, storage, selectorMatches };
}
