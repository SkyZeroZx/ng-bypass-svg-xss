import { Component } from '@angular/core';

// The bound value is not a file the attacker uploaded, it is one of the app's
// own XML endpoints.
@Component({
  selector: 'app-xml-endpoint',
  templateUrl: './xml-endpoint.html',
})
export class XmlEndpointCase {
  readonly apiUrl = '/api/profile.xml#x';
}
