const validators = {
	v: {
		required: true,
		description: 'The v tag is required and represents the protocol version. An example is v=BIMI1',
		validate(term, value) {
			if (value !== 'BIMI1') {
				throw new Error(`Invalid BIMI version: '${value}'`);
			}
		}
	},
	l: {
		description: 'The l tag pertains to how logo are created and presented to BIMI users.',
		validate(term, originalValue) {
			var value = originalValue.split(':');
			if (value.length <= 2) {
				if (!value[0].includes('https')) {
					throw new Error(`Invalid value for '${term}': '${originalValue}', must be https`);
				}
			}
		},
		generate(value) {
			if (value && value.length)
				return value;
			throw new Error("Invalid for 'l' tag")
		}
	},
	a: {
		description: 'The a tag pertains to how certificate are created and presented to BIMI users.',
		validate(term, originalValue) {
			var value = originalValue.split(':');
			if (value.length <= 2) {
				if (!value[0].includes('https')) {
					throw new Error(`Invalid value for '${term}': '${originalValue}', must be https`);
				}
			}
		},
		generate(value) {
			if (value && value.length)
				return value;
			throw new Error("Invalid for 'a' tag")
		}
	},
};

module.exports = validators;