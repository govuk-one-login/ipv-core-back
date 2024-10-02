import { readFile } from "fs/promises";
import { Schema, Validator } from "jsonschema";
import YAML from "yaml";

interface OpenApiSchema {
  components: {
    schemas: Record<string, Schema>;
  };
}

interface VocabSchema extends Schema {
  $defs: Record<string, Schema>;
}

// Fetch an external schema from https://vocab.account.gov.uk
const fetchVocabSchema = async (ref: string): Promise<VocabSchema> => {
  const refUri = new URL(ref);
  if (refUri.origin !== "https://vocab.account.gov.uk") {
    throw new Error(`Refusing to import schema from ${ref}`);
  }
  const res = await fetch(refUri);
  if (!res.ok) {
    throw new Error(`Could not import schema ${ref}, status ${res.status}`);
  }
  const vocabSchema = (await res.json()) as VocabSchema;
  // The schema IDs in the vocab schema are non-unique and don't match their URLs
  // so we override them here instead
  vocabSchema.$id = ref;
  return vocabSchema;
};

export const createValidator = async (
  openApiPath: string,
): Promise<Validator> => {
  const validator = new Validator();
  const openApiSchema = YAML.parse(
    await readFile(openApiPath, "utf-8"),
  ) as OpenApiSchema;

  Object.entries(openApiSchema.components.schemas).forEach(([key, schema]) =>
    validator.addSchema(schema, `/${key}`),
  );

  for (const ref of validator.unresolvedRefs) {
    const schema = await fetchVocabSchema(ref);
    validator.addSchema(schema);

    // The vocab schemas contain nested definitions, which need to be added as well
    for (const [nestedName, nestedSchema] of Object.entries(schema.$defs)) {
      validator.addSchema(nestedSchema, `${ref}#/$defs/${nestedName}`);
    }
  }

  return validator;
};
