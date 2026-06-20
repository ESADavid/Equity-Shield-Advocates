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
    '@babel/plugin-transform-class-static-block',
  ],
  env: {
    test: {
      presets: [
        [
          '@babel/preset-env',
          {
            targets: { node: 'current' },
            modules: 'commonjs',
          },
        ],
        '@babel/preset-typescript',
      ],
      plugins: [
        '@babel/plugin-transform-runtime',
        '@babel/plugin-transform-private-methods',
        '@babel/plugin-transform-class-static-block',
      ],
    },
  },
};
