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

const VOCAB_ORIGIN = "https://vocab.account.gov.uk";

// Fetch an external schema from https://vocab.account.gov.uk
const fetchVocabSchema = async (ref: string): Promise<VocabSchema> => {
  const refUri = new URL(ref);
  if (refUri.origin !== VOCAB_ORIGIN) {
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

// Because API Gateway doesn't support the $ref field linking to external schemas
// we store the ref on a non-standard property and rewrite it here
const restoreRefs = (schema: Schema): void => {
  if (
    schema.type === "object" &&
    schema.description?.startsWith(VOCAB_ORIGIN)
  ) {
    schema.$ref = schema.description;
    delete schema.type;
  }

  if (schema.items) {
    if (Array.isArray(schema.items)) {
      schema.items.forEach(restoreRefs);
    } else {
      restoreRefs(schema.items);
    }
  }

  if (schema.properties) {
    Object.values(schema.properties).forEach(restoreRefs);
  }
};

export const createValidator = async (
  openApiPath: string,
): Promise<Validator> => {
  const validator = new Validator();
  const schemaFile = await readFile(openApiPath, "utf-8");
  const openApiSchema = YAML.parse(schemaFile) as OpenApiSchema;

  Object.entries(openApiSchema.components.schemas).forEach(([key, schema]) => {
    restoreRefs(schema);
    validator.addSchema(schema, `/${key}`);
  });

  while (validator.unresolvedRefs.length) {
    const ref = validator.unresolvedRefs[0];
    const schema = await fetchVocabSchema(ref);
    validator.addSchema(schema);

    // The vocab schemas contain nested definitions, which need to be added as well
    for (const [nestedName, nestedSchema] of Object.entries(schema.$defs)) {
      validator.addSchema(nestedSchema, `${ref}#/$defs/${nestedName}`);
    }
  }

  return validator;
};
