# ESLint and NPM Fix Plan - Approved and In Progress

## Steps to Complete:

- [ ] Step 1: Edit root package.json 
  - Remove "overrides" section with @mapbox/node-pre-gyp
  - Update axios to ^1.7.7
  - Add devDeps: "eslint-plugin-prettier": "^5.4.1", "eslint-config-prettier": "^10.1.5"
  - Update lint:fix script to target: app.js, routes/**/*, services/**/*, models/**/*, middleware/**/*, utils/**/*, config/**/* --ext .js,.ts --fix (exclude sub-projects)

- [ ] Step 2: Edit root .eslintrc.cjs 
  - Add 'owlbangroup.io/' to ignorePatterns array

- [ ] Step 3: Clean npm install 
  - rmdir /s node_modules &amp;&amp; del package-lock.json &amp;&amp; npm install

- [ ] Step 4: Run root lint fix 
  - npm run lint:fix

- [ ] Step 5: Lint owlbangroup.io sub-project 
  - cd owlbangroup.io &amp;&amp; npm install &amp;&amp; npm run lint:fix

- [ ] Step 6: Run tests 
  - npm test

- [ ] Step 7: Verify all lints pass and no errors, complete task

**Current Status: Starting edits...**

