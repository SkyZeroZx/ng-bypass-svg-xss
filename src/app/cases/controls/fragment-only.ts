import { Component } from '@angular/core';

// The bound value here is the hostile one -- the attacker's icon id is a whole
// URL, trying to move the reference to the file they uploaded.
@Component({
  selector: 'app-fragment-only',
  templateUrl: './fragment-only.html',
})
export class FragmentOnlyCase {
  readonly attackerIconId = '/asset.svg#x';
  readonly iconUrl = '/safe.svg#' + this.attackerIconId;
}
