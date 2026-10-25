import { Component } from '@angular/core';

@Component({
  selector: 'app-same-origin-href',
  templateUrl: './same-origin-href.html',
})
export class SameOriginHrefCase {
  readonly assetUrl = '/asset.svg#x';
}
