# Contributing to Oscar Broome Revenue System

Thank you for your interest in contributing to the Oscar Broome Revenue System! This document provides guidelines and instructions for contributing to this project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Guidelines](#coding-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## 🤝 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). By participating, you are expected to uphold this code.

## 🚀 Getting Started

### Prerequisites

- Node.js v18.0.0 or higher
- npm v9.0.0 or higher
- MySQL 8.0 or higher
- Git
- A GitHub account

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/oscar-broome-revenue.git
cd oscar-broome-revenue
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/Owlban-Group/oscar-broome-revenue.git
```

## 💻 Development Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
# See .env.example for detailed descriptions of each variable
```

### 3. Set Up Database

```bash
# Create the database
mysql -u root -p < scripts/create_database.sql

# Run migrations
npm run migrate
```

### 4. Start Development Server

```bash
# Start the backend server
npm run dev

# In a separate terminal, start the dashboard
npm run dev:dashboard
```

## 🔧 How to Contribute

### Types of Contributions

We welcome the following types of contributions:

- 🐛 **Bug Fixes**: Fix issues and improve stability
- ✨ **New Features**: Add new functionality
- 📝 **Documentation**: Improve or add documentation
- 🎨 **UI/UX**: Enhance user interface and experience
- ⚡ **Performance**: Optimize code and improve performance
- 🧪 **Tests**: Add or improve test coverage
- 🔒 **Security**: Enhance security measures

### Before You Start

1. **Check existing issues**: Search for existing issues or feature requests
2. **Create an issue**: If none exists, create one to discuss your proposed changes
3. **Get feedback**: Wait for maintainer feedback before starting work
4. **Assign yourself**: Comment on the issue to let others know you're working on it

## 📝 Coding Guidelines

### Code Style

- **ES6+ Syntax**: Use modern JavaScript features
- **Async/Await**: Prefer async/await over callbacks
- **Arrow Functions**: Use arrow functions for callbacks
- **Const/Let**: Use `const` by default, `let` when reassignment is needed
- **Template Literals**: Use template literals for string interpolation

### Naming Conventions

```javascript
// Variables and functions: camelCase
const userName = 'John';
function getUserData() {}

// Classes: PascalCase
class UserService {}

// Constants: UPPER_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 3;

// Private methods: prefix with underscore
class Example {
  _privateMethod() {}
}

// Files: kebab-case for utilities, PascalCase for classes
// user-service.js, UserModel.js
```

### Logging

**DO NOT use console.log in production code**. Use the Winston logger instead:

```javascript
import { logger, logInfo, logError, logWarn } from './config/logger.js';

// Good ✅
logInfo('User logged in', { userId: user.id });
logError('Database connection failed', error);
logWarn('Rate limit approaching', { requests: count });

// Bad ❌
console.log('User logged in');
console.error('Database connection failed');
```

### Error Handling

Always use proper error handling:

```javascript
// Good ✅
try {
  const result = await someAsyncOperation();
  logInfo('Operation successful', { result });
  return result;
} catch (error) {
  logError('Operation failed', error, { context: 'someOperation' });
  throw new AppError('Operation failed', 500, error);
}

// Bad ❌
try {
  const result = await someAsyncOperation();
  console.log(result);
} catch (error) {
  console.error(error);
}
```

### Module System

This project uses **ES Modules**. Always use `import/export`:

```javascript
// Good ✅
import express from 'express';
export const router = express.Router();

// Bad ❌
const express = require('express');
module.exports = router;
```

### Comments

- Write self-documenting code when possible
- Add comments for complex logic
- Use JSDoc for functions and classes

```javascript
/**
 * Processes a payment transaction
 * @param {Object} transaction - The transaction object
 * @param {string} transaction.amount - Transaction amount
 * @param {string} transaction.currency - Currency code
 * @returns {Promise<Object>} Processed transaction result
 * @throws {PaymentError} If payment processing fails
 */
async function processPayment(transaction) {
  // Implementation
}
```

## 🧪 Testing Requirements

### Writing Tests

All new features and bug fixes must include tests:

```javascript
// Example test structure
describe('UserService', () => {
  describe('createUser', () => {
    it('should create a new user with valid data', async () => {
      const userData = { username: 'test', email: 'test@example.com' };
      const user = await UserService.createUser(userData);
      expect(user).toBeDefined();
      expect(user.username).toBe('test');
    });

    it('should throw error with invalid email', async () => {
      const userData = { username: 'test', email: 'invalid' };
      await expect(UserService.createUser(userData)).rejects.toThrow();
    });
  });
});
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:jpmorgan
npm run test:merchant
npm run test:payroll

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

### Test Coverage Requirements

- **Minimum coverage**: 70% overall
- **Critical paths**: 90% coverage required
- **New features**: Must include tests
- **Bug fixes**: Must include regression tests

## 🔄 Pull Request Process

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create a feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 2. Make Your Changes

- Write clean, well-documented code
- Follow the coding guidelines
- Add tests for your changes
- Update documentation as needed

### 3. Commit Your Changes

We use [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: <type>(<scope>): <subject>

git commit -m "feat(auth): add two-factor authentication"
git commit -m "fix(payment): resolve Stripe webhook validation"
git commit -m "docs(readme): update installation instructions"
git commit -m "test(payroll): add integration tests"
```

**Commit Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes

### 4. Run Quality Checks

```bash
# Run linter
npm run lint

# Fix linting issues
npm run lint:fix

# Run tests
npm test

# Check test coverage
npm run test:coverage
```

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
# Fill in the PR template with all required information
```

### 6. PR Review Process

- Maintainers will review your PR
- Address any requested changes
- Keep your PR up to date with main branch
- Once approved, a maintainer will merge your PR

## 📊 Pull Request Checklist

Before submitting your PR, ensure:

- [ ] Code follows the project's coding guidelines
- [ ] All tests pass (`npm test`)
- [ ] Linting passes (`npm run lint`)
- [ ] New tests added for new features/fixes
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventional commits format
- [ ] PR description clearly explains the changes
- [ ] No merge conflicts with main branch
- [ ] Screenshots/GIFs included for UI changes
- [ ] Breaking changes are clearly documented

## 🐛 Issue Reporting

### Before Creating an Issue

1. **Search existing issues**: Check if the issue already exists
2. **Check documentation**: Review docs and README
3. **Try latest version**: Ensure you're using the latest version
4. **Reproduce the issue**: Verify you can consistently reproduce it

### Creating a Good Issue

Use our issue templates:

- **Bug Report**: For reporting bugs
- **Feature Request**: For suggesting new features

Include:

- Clear, descriptive title
- Detailed description
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment information
- Screenshots/logs
- Code snippets (if applicable)

## 🔒 Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:

1. Email security@oscarbroome.com
2. Or use GitHub's private security advisory feature
3. Include detailed information about the vulnerability
4. Allow time for the issue to be addressed before public disclosure

## 📚 Additional Resources

- [Project Documentation](./docs/)
- [API Documentation](./API_DOCUMENTATION.md)
- [Control Center User Guide](./CONTROL_CENTER_USER_GUIDE.md)
- [Deployment Instructions](./DEPLOYMENT_INSTRUCTIONS.md)

## 💬 Questions?

- Create a [Discussion](https://github.com/Owlban-Group/oscar-broome-revenue/discussions)
- Check existing documentation
- Review closed issues for similar questions

## 🙏 Thank You!

Your contributions make this project better for everyone. We appreciate your time and effort!

---

**Happy Coding! 🚀**
