import { Scheme } from '../models/enums.mjs';

export const text = value => {
  if (typeof value !== 'string') throw new TypeError('Expected a string');
  if (value.includes('\0')) throw new TypeError('Embedded NUL is forbidden');
  return value;
};
export const schemeValue = value => {
  if (!Object.values(Scheme).includes(value)) throw new RangeError('Unknown ABE scheme');
  return value;
};

export const parameterValue = (value, enumeration) => {
  if (!Object.values(enumeration).includes(value)) throw new RangeError('Unknown parameter set');
  return value;
};

