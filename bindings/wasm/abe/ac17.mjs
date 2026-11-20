import { FunctionalCPABE } from './base.mjs';
import { Scheme } from '../models/enums.mjs';

export class AC17CPABE extends FunctionalCPABE {
  constructor(native) { super(native, Scheme.AC17); }
}
