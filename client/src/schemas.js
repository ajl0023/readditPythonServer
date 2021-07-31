import { schema } from "normalizr";
export const comment = new schema.Entity("comments", {}, { idAttribute: "id" });
comment.define({
  comments: [comment],
});
export const post = new schema.Entity(
  "posts",
  {},

  { idAttribute: "id" }
);
