// Test ITG routes import
import itgRoutes from './routes/itgRoutes.js';
console.log('✓ itgRoutes loaded');
console.log('  Routes:', itgRoutes.stack ? itgRoutes.stack.length + ' routes defined' : 'Router loaded');

// Check route definitions
if (itgRoutes.stack) {
  const routes = itgRoutes.stack
    .filter(layer => layer.route)
    .map(layer => layer.route.path);
  console.log('  Defined routes:', routes);
}

console.log('\n✅ ITG Routes imported successfully!');
