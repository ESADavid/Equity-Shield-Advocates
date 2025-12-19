module.exports = {
  presets: [
    [
      '@babel/preset-env',
      {
        targets: { node: 'current' },
        // Transform modules to CommonJS for Jest, but keep ES modules for other tools
        modules: process.env.NODE_ENV === 'test' ? 'commonjs' : false,
      },
    ],
    '@babel/preset-typescript',
  ],
  plugins: [
    '@babel/plugin-transform-runtime',
    '@babel/plugin-transform-private-methods',
    '@babel/plugin-syntax-import-meta',
  ],
  ignore: ['node_modules'],
};
