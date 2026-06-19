// @ts-nocheck
/**
 * Mock for sinon library
 * Used by tests that need sinon stubs/spies but don't have it installed
 */

// Simple mock implementation
const createStub = () => {
  const stubFn = (...args) => {
    if (stubFn.returns) return stubFn.returns;
    if (stubFn.throws) throw stubFn.throws;
    return undefined;
  };
  
  stubFn.returns = (value) => {
    stubFn.returns = value;
    return stubFn;
  };
  
  stubFn.throws = (error) => {
    stubFn.throws = typeof error === 'string' ? new Error(error) : error;
    return stubFn;
  };
  
  stubFn.callsFake = (fn) => {
    stubFn._callsFake = fn;
    return stubFn;
  };
  
  stubFn.withArgs = (...args) => stubFn;
  stubFn.calledOnce = false;
  stubFn.called = false;
  stubFn.callCount = 0;
  
  return stubFn;
};

const createSpy = () => {
  const spyFn = (...args) => {
    spyFn.callCount++;
    spyFn.called = true;
    spyFn.lastCall = args;
    spyFn.calls.push(args);
    if (spyFn._callsFake) return spyFn._callsFake(...args);
    return undefined;
  };
  
  spyFn.callCount = 0;
  spyFn.called = false;
  spyFn.calls = [];
  spyFn.lastCall = null;
  spyFn.callsFake = (fn) => {
    spyFn._callsFake = fn;
    return spyFn;
  };
  
  return spyFn;
};

const createMock = () => {
  const mockFn = (...args) => mockFn;
  mockFn._returns = undefined;
  mockFn.returns = (value) => {
    mockFn._returns = value;
    return mockFn;
  };
  
  return mockFn;
};

// Main sinon exports
export const stub = createStub;
export const spy = createSpy;
export const mock = createMock;
export const createStubInstance = (Constructor) => new Constructor();

// Chai sinon integration
export const sandbox = {
  create: () => ({
    stub: createStub,
    spy: createSpy,
    mock: createMock,
    restore: () => {},
  }),
};

export default {
  stub,
  spy,
  mock,
  createStubInstance,
  sandbox,
};
