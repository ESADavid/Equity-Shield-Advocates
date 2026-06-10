// Quick test to verify ITG modules can be imported
import SacredGeometry from './algorithms/sacredGeometry.js';
import DivineWisdom from './algorithms/divineWisdom.js';
import { getKingSachemYochananITG } from './services/kingSachemYochananITG.js';

console.log('Testing ITG module imports...');

// Test SacredGeometry
const sg = new SacredGeometry();
console.log('✓ SacredGeometry loaded, phi =', sg.phi);

// Test DivineWisdom
const dw = new DivineWisdom();
console.log('✓ DivineWisdom loaded, principles =', Object.keys(dw.kingdomPrinciples).length);

// Test KingSachemYochananITG
const itg = getKingSachemYochananITG();
console.log('✓ KingSachemYochananITG loaded, king =', itg.kingName);

console.log('\n✅ All ITG modules imported successfully!');
