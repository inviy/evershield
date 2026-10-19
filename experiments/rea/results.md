| Leak | Recovered from the leaky app | evershield flags it | Recovered after the fix |
|---|---|---|---|
| Stripe secret key in the bundle | yes (rea inspect, rea bundle, rea static) | `artifact/secret-like-string` critical/high | no |
| Internal API address in the bundle | yes (rea inspect, rea bundle, rea static) | `artifact/internal-endpoint` medium/medium | no |
| Original source via a published source map (comments, file layout) | yes (rea bundle) | `artifact/source-map-published` high/high | no |
| Pro metric in the free user's page, hidden by blur | yes (rea inspect) | `surface/hidden-higher-tier-content` high/high<br>`surface/obscured-content` high/medium | no |
| Pro fields in the free user's API response | yes (free user's response) | `response/expected-absent-field-present` high/high | no |

evershield findings on the fixed app: 0.
