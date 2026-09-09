import {build} from 'esbuild';
await build({entryPoints:['server/node.ts'],outfile:'dist/server.js',bundle:true,platform:'node',format:'esm',packages:'external',target:'node24'});
