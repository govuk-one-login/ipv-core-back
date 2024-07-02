export default {
  parallel: 2,
  format: ["html:cucumber-report.html"],
  publish: true,
  retry: 1,
  loader: ["ts-node/esm"],
  import: ["src/steps/**/*.ts", "src/config/**/*.ts"],
};
