import { Component } from '@angular/core';

@Component({
  selector: 'app-same-origin-xlink',
  templateUrl: './same-origin-xlink.html',
})
export class SameOriginXlinkCase {
  readonly assetUrl = '/asset.svg#x';
}
