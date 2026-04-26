"use strict";

function CoverPage({ data, helpers }) {
  const { React, Page, Text, Footer, AccentBar, MetaRow, HR, S } = helpers;

  return React.createElement(
    Page,
    { size: "A4", style: S.page },
    React.createElement(AccentBar),
    React.createElement(Text, { style: S.h1 }, "ASRFacet-Rb Recon Report"),
    React.createElement(MetaRow, { label: "Target", value: data.meta.target }),
    React.createElement(MetaRow, { label: "Generated", value: data.meta.generated }),
    React.createElement(MetaRow, { label: "Version", value: `v${data.meta.version}` }),
    React.createElement(HR),
    React.createElement(Footer, { version: data.meta.version })
  );
}

module.exports = CoverPage;
