# IPV Core Journey Map

This is a small JavaScript-based tool to display the journey map in an interactive page

## Prerequisites

- Node and NPM installed

## Running the map

- Run `npm install` to install dependencies.
- Run `npm start` to load the application
- Open [http://localhost:3000] in a web browser

## Using the map

You should be able to pan and zoom using the mouse and scroll wheel,
as well as viewing the differences when a CRI is marked as disabled, or a particular feature flag is enabled.

N.B. for clarity, the map only displays states that are accessible via preconfigured entry states.

## Implementation

We run a very lightweight express server to serve the static HTML and JS,
and provide a route to expose the journey map as a JSON object.

The frontend converts this to mermaid format, and renders using two publicly available libraries:
- [mermaid-js](https://mermaid.js.org/)
- [svg-pan-zoom](https://github.com/bumbu/svg-pan-zoom)
