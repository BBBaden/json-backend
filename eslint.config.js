import eslint from "@eslint/js"
import prettier from "eslint-config-prettier"
import globals from "globals"

export default [
	{
		languageOptions: {
			globals: { ...globals.node },
		},
		rules: { "no-unused-vars": ["error", { argsIgnorePattern: "^_" }] },
	},
	eslint.configs.recommended,
	prettier,
]
