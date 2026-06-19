/**
 * Large Number Sets Utility
 * Contains number sets beyond quadrillion including:
 * - quadrillion (10^15)
 * - quintillion (10^18)
 * - sextillion (10^21)
 * - septillion (10^24)
 * - octillion (10^27)
 * - nonillion (10^30)
 * - decillion (10^33)
 * - undecillion (10^36)
 * - duodecillion (10^39)
 * - tredecillion (10^42)
 */

/**
 * Large number names and their corresponding values
 * Using standard American naming convention
 */
export const LARGE_NUMBER_SETS = {
  // Names in order from smallest to largest
  quadrillion: {
    name: 'quadrillion',
    shortName: 'Q',
    exponent: 15,
    value: 1e15,
    symbol: 'Qa'
  },
  quintillion: {
    name: 'quintillion',
    shortName: 'Qi',
    exponent: 18,
    value: 1e18,
    symbol: 'Qn'
  },
  sextillion: {
    name: 'sextillion',
    shortName: 'Sx',
    exponent: 21,
    value: 1e21,
    symbol: 'Sx'
  },
  septillion: {
    name: 'septillion',
    shortName: 'Sp',
    exponent: 24,
    value: 1e24,
    symbol: 'Sp'
  },
  octillion: {
    name: 'octillion',
    shortName: 'Oc',
    exponent: 27,
    value: 1e27,
    symbol: 'Oc'
  },
  nonillion: {
    name: 'nonillion',
    shortName: 'No',
    exponent: 30,
    value: 1e30,
    symbol: 'No'
  },
  decillion: {
    name: 'decillion',
    shortName: 'Dc',
    exponent: 33,
    value: 1e33,
    symbol: 'Dc'
  },
  undecillion: {
    name: 'undecillion',
    shortName: 'UD',
    exponent: 36,
    value: 1e36,
    symbol: 'UD'
  },
  duodecillion: {
    name: 'duodecillion',
    shortName: 'DD',
    exponent: 39,
    value: 1e39,
    symbol: 'DD'
  },
  tredecillion: {
    name: 'tredecillion',
    shortName: 'TD',
    exponent: 42,
    value: 1e42,
    symbol: 'TD'
  }
};

/**
 * Get the numeric value for a given large number name
 * @param {string} name - The name of the large number (e.g., 'quadrillion', 'quintillion')
 * @returns {number|null} The numeric value or null if not found
 */
export function getLargeNumberValue(name) {
  const key = name?.toLowerCase();
  return LARGE_NUMBER_SETS[key]?.value ?? null;
}

/**
 * Get the exponent for a given large number name
 * @param {string} name - The name of the large number
 * @returns {number|null} The exponent (power of 10) or null if not found
 */
export function getLargeNumberExponent(name) {
  const key = name?.toLowerCase();
  return LARGE_NUMBER_SETS[key]?.exponent ?? null;
}

/**
 * Get the full object for a given large number name
 * @param {string} name - The name of the large number
 * @returns {object|null} The large number object or null if not found
 */
export function getLargeNumber(name) {
  const key = name?.toLowerCase();
  return LARGE_NUMBER_SETS[key] ?? null;
}

/**
 * Get all large number names as an array
 * @returns {string[]} Array of all large number names
 */
export function getAllLargeNumberNames() {
  return Object.keys(LARGE_NUMBER_SETS);
}

/**
 * Get all large numbers sorted by exponent
 * @param {string} order - 'asc' for ascending, 'desc' for descending
 * @returns {object[]} Array of large number objects
 */
export function getSortedLargeNumbers(order = 'asc') {
  const numbers = Object.values(LARGE_NUMBER_SETS);
  return order === 'desc' 
    ? numbers.sort((a, b) => b.exponent - a.exponent)
    : numbers.sort((a, b) => a.exponent - b.exponent);
}

/**
 * Convert a number to its large number name if applicable
 * @param {number} value - The numeric value
 * @returns {string|null} The name of the large number or null if not applicable
 */
export function numberToLargeNumberName(value) {
  if (!value || value < 1e15) return null;
  
  for (const [name, data] of Object.entries(LARGE_NUMBER_SETS)) {
    if (Math.abs(value - data.value) < 1) {
      return name;
    }
  }
  return null;
}

/**
 * Format a number with its large number suffix
 * @param {number} value - The numeric value
 * @returns {string} Formatted string with large number name
 */
export function formatWithLargeNumber(value) {
  const name = numberToLargeNumberName(value);
  if (!name) return value.toString();
  
  const data = LARGE_NUMBER_SETS[name];
  const scaledValue = value / data.value;
  return `${scaledValue} ${data.name}`;
}

/**
 * Default export - all large number sets
 */
export default LARGE_NUMBER_SETS;
