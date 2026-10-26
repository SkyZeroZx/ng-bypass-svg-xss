import { Component } from '@angular/core';

// `clicks` is rendered so a row can tell whether the app's own handler ran as
// well.
@Component({
  selector: 'app-use-inside-button',
  templateUrl: './use-inside-button.html',
})
export class UseInsideButtonCase {
  readonly iconUrl = '/asset.svg#x';
  clicks = 0;
}
