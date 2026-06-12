import globals from "globals";

export default [
  {
    ignores: ["dist/", "node_modules/", "src-tauri/"],
  },
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      "no-unused-vars": "warn",
      "no-undef": "error",
      "no-var": "error",
      "prefer-const": "warn",
      "no-unused-expressions": "warn",
      "no-empty": "warn",
      "eqeqeq": "warn",
    },
  },
];
