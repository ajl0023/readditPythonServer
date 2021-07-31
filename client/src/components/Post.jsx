import DeleteIcon from "@material-ui/icons/Delete";
import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { deletePost, fetchSinglePost } from "../actions/postActions";
import { ReactComponent as DownArrow } from "../images/down-arrow.svg";
import { ReactComponent as UpArrow } from "../images/up-arrow.svg";
const Post = ({ post, history }) => {
  const [deleteButton, setDelete] = useState(false);
  const [, setActive] = useState(true);
  const params = history.match.params.sort;
  const dispatch = useDispatch();
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const currentUser = useSelector((state) => state.currentUser.id);
  const postStatus = useSelector((state) => state.listings.status);
  const handleDelete = () => {
    setDelete(!deleteButton);
  };
  const confirmedDelete = (postId) => {
    dispatch(deletePost(postId, params === "post" ? null : params));
    setActive(false);
  };
  if (!post) {
    return null;
  }
  return (
    <>
      <div
        key={post.id}
        className={`card-container ${
          checkDisplay === "dark" ? "dark-mode-card" : ""
        } `}
      >
        <div
          className={`card-content-container ${
            postStatus === "loading" ? "content-loading-mask" : ""
          }`}
        >
          <p className={"card-author"}>
            u/{post.author ? post.author.username : "deleted"}
          </p>
          <h4 className="card-title">
            <Link
              onClick={() => {
                dispatch(fetchSinglePost(post.id));
              }}
              to={{
                pathname: `/post/${post.id}`,
                state: {
                  modal: true,
                },
              }}
            >
              {post.title}
            </Link>
          </h4>
          <div className="vote-container">
            <li>
              <UpArrow
                className={
                  post.voteState === 1
                    ? `home-vote-color`
                    : `${checkDisplay === "dark" ? "dark-mode-arrow" : ""}`
                }
                alt=""
              />
            </li>
            <li>{post.voteTotal}</li>
            <li>
              <DownArrow
                className={
                  post.voteState === -1
                    ? `home-vote-color`
                    : `${checkDisplay === "dark" ? "dark-mode-arrow" : ""}`
                }
                alt=""
              />
            </li>
          </div>
        </div>
        {post.author && currentUser === post.author.id ? (
          <div className="edit-del-container">
            <div className="edit-del-content">
              {deleteButton ? (
                <div className="delete-confirm-container">
                  <div>
                    <p className="delete-confirm">Delete?</p>
                  </div>
                  <li
                    onClick={() => confirmedDelete(post.id)}
                    className="delete-button-yes"
                  >
                    Yes
                  </li>
                  <li className="delete-button-slash">/</li>
                  <li className="delete-button-yes">No</li>
                </div>
              ) : null}
              <button onClick={handleDelete} className="delete-button">
                <DeleteIcon className="del-svg" />
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
};
// export default React.memo(Post, (prev, next) => {
//   //     prev: prev.post,
//     next: next.post,
//   });

//   // if (prev.post.voteTotal === next.post.voteTotal) {
//   //   return true;
//   // }
// });
export default Post;
