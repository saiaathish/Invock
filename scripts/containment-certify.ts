import { certifyContainment } from "../src/containment/certification.js";

const result = await certifyContainment();
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.status === "pass" ? 0 : result.status === "fail" ? 1 : 2;
