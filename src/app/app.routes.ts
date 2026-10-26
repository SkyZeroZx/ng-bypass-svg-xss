import { Routes } from '@angular/router';
import { SameOriginHrefCase } from './cases/same-origin/same-origin-href';
import { SameOriginXlinkCase } from './cases/same-origin/same-origin-xlink';
import { SameOriginFragmentlessCase } from './cases/same-origin/same-origin-fragmentless';
import { FragmentOnlyCase } from './cases/controls/fragment-only';
import { XmlEndpointCase } from './cases/same-origin/xml-endpoint';
import { UseInsideAnchorCase } from './cases/template-shape/use-inside-anchor';
import { UseInsideButtonCase } from './cases/template-shape/use-inside-button';
import { ControlsCase } from './cases/controls/controls';
import { DataUrlCase } from './cases/data-url/data-url';
import { DataConstructedCase } from './cases/data-url/data-constructed';

export const routes: Routes = [
  { path: '', redirectTo: 'case/same-origin-svg', pathMatch: 'full' },
  { path: 'case/same-origin-svg', component: SameOriginHrefCase },
  { path: 'case/same-origin-xlink', component: SameOriginXlinkCase },
  { path: 'case/same-origin-fragmentless', component: SameOriginFragmentlessCase },
  { path: 'case/fragment-only', component: FragmentOnlyCase },
  { path: 'case/xml-endpoint', component: XmlEndpointCase },
  { path: 'case/use-inside-anchor', component: UseInsideAnchorCase },
  { path: 'case/use-inside-button', component: UseInsideButtonCase },
  { path: 'case/data-svg', component: DataUrlCase },
  { path: 'case/data-constructed', component: DataConstructedCase },
  { path: 'case/safe-sprite-and-img', component: ControlsCase },
];
