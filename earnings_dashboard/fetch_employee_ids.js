"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetchEmployeeIds = fetchEmployeeIds;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const employeeIdsFilePath = path_1.default.resolve(__dirname, '../owlban_repos/sample_repo/employee_ids.json');
/**
 * Fetch employee IDs dynamically from a JSON file.
 * This simulates dynamic fetching and can be replaced with API calls or database queries.
 */
async function fetchEmployeeIds() {
    try {
        const data = fs_1.default.readFileSync(employeeIdsFilePath, 'utf-8');
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
