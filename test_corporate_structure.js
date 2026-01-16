import OwlbanGroup from './corporateStructure.js';

const owlban = new OwlbanGroup();

console.log('Designer Compensation (Payroll):', owlban.getDesignerCompensation());
console.log('Total Revenue:', owlban.getTotalRevenue());
console.log('Hierarchy:', JSON.stringify(owlban.getHierarchy(), null, 2));
