/** esbuild's `dataurl` loader turns an image import into a string. Declared so
 * TypeScript agrees, since there is no bundler plugin to infer it from. */
declare module '*.png' {
  const dataUri: string;
  export default dataUri;
}
