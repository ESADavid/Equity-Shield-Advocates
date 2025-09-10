export interface EmployeeId {
  id: string;
  name: string;
  department?: string;
}

export declare function fetchEmployeeIds(): Promise<EmployeeId[]>;

export default fetchEmployeeIds;
