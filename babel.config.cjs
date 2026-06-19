module.exports = {
  presets: [
    [
      '@babel/preset-env',
      {
        targets: { node: 'current' },
        // Use 'auto' to let Babel detect CommonJS vs ESM
        modules: 'auto',
      },
    ],
    '@babel/preset-typescript',
  ],
  plugins: [
    '@babel/plugin-transform-runtime',
    '@babel/plugin-transform-private-methods',
  ],
  // Force CommonJS for Jest test environment
  env: {
    test: {
      presets: [
        [
          '@babel/preset-env',
          {
            targets: { node: 'current' },
            // Force CommonJS for Jest tests to avoid ESM issues
            modules: 'commonjs',
          },
        ],
        '@babel/preset-typescript',
      ],
      plugins: [
        '@babel/plugin-transform-runtime',
        '@babel/plugin-transform-private-methods',
      ],
    },
  },
};
