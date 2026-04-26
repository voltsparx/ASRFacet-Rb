"use strict";

function buildCover(data, helpers) {
  return [
    helpers.heading1("ASRFacet-Rb Recon Report"),
    helpers.labelValue("Target", data.meta.target),
    helpers.labelValue("Generated", data.meta.generated),
    helpers.labelValue("Version", `v${data.meta.version}`),
    helpers.hr(),
  ];
}

module.exports = buildCover;
