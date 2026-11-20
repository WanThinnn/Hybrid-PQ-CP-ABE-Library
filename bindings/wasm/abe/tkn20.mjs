import { FunctionalCPABE } from './base.mjs';
import { Scheme } from '../models/enums.mjs';

export class TKN20CPABE extends FunctionalCPABE {
  constructor(native) { super(native, Scheme.TKN20); }
}
