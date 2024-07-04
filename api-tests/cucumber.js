export default {
  parallel: 2,
  format: [
    "html:reports/api-tests-cucumber-report.html",
    "json:reports/api-tests-cucumber-report.json",
  ],
  publish: true,
  retry: 1,
  loader: ["ts-node/esm"],
  import: ["src/steps/**/*.ts", "src/config/**/*.ts"],
};
