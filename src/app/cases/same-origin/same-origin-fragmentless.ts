import { Component } from '@angular/core';

// No string concatenation and no # anywhere: the bound value is the bare path
// the application got from its own API.
@Component({
  selector: 'app-same-origin-fragmentless',
  templateUrl: './same-origin-fragmentless.html',
})
export class SameOriginFragmentlessCase {
  readonly assetUrl = '/asset.svg';
}
