import { Routes } from '@angular/router';
import { SameOriginHrefCase } from './cases/href/same-origin-href';
import { SameOriginXlinkCase } from './cases/xlink/same-origin-xlink';
import { ControlsCase } from './cases/controls/controls';
import { DataUrlCase } from './cases/data-url/data-url';
import { DataConstructedCase } from './cases/data-constructed/data-constructed';

export const routes: Routes = [
  { path: '', redirectTo: 'case/same-origin-svg', pathMatch: 'full' },
  { path: 'case/same-origin-svg', component: SameOriginHrefCase },
  { path: 'case/same-origin-xlink', component: SameOriginXlinkCase },
  { path: 'case/data-svg', component: DataUrlCase },
  { path: 'case/data-constructed', component: DataConstructedCase },
  { path: 'case/safe-sprite-and-img', component: ControlsCase },
];
