module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' }, modules: false }],
    '@babel/preset-typescript'
  ],
  plugins: [
    '@babel/plugin-transform-runtime',
    '@babel/plugin-transform-private-methods',
    '@babel/plugin-syntax-import-meta'
  ],
  ignore: [
    "node_modules"
  ]
};
