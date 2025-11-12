"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetchEmployeeIds = fetchEmployeeIds;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const employeeIdsFilePath = path.resolve(__dirname, '../owlban_repos/sample_repo/employee_ids.json');
/**
 * Fetch employee IDs dynamically from a JSON file.
 * This simulates dynamic fetching and can be replaced with API calls or database queries.
 */
async function fetchEmployeeIds() {
    try {
        const data = fs.readFileSync(employeeIdsFilePath, 'utf-8');
        const employeeIds = JSON.parse(data);
        if (Array.isArray(employeeIds)) {
            return employeeIds;
        }
        else {
            console.warn('Employee IDs data is not an array, returning empty list.');
            return [];
        }
    }
    catch (error) {
        console.error('Failed to read employee IDs file:', error);
        return [];
    }
}
//# sourceMappingURL=fetch_employee_ids.js.map