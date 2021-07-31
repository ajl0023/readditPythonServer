import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link, useLocation, useParams } from "react-router-dom";

import {
  fetchPosts,
  fetchSinglePost,
  newPostSubmissionType,
  nextPage,
  submitPostAttempt,
} from "../actions/postActions";
import imagePost from "../images/image-placeholder.svg";
import linkPost from "../images/link-post.svg";
import defaultPic from "../images/reddit-default.svg";
import Post from "./Post";
import Signup from "./Signup";
function Home(props) {
  const dispatch = useDispatch();
  const allPosts = useSelector((state) => {
    return state.posts.byId;
  });
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const [dataLoaded, setDataLoaded] = useState(false);
  const location = useLocation();
  const loggedIn = useSelector((state) => state.login.isLoggedIn);
  const postStatus = useSelector((state) => state.posts.status);
  const params = useParams();
  const listingOrder = useSelector((state) => state.listings.listingOrder);
  const sortOrder = useSelector((state) => state.listings.sortOrder);
  const currentIds = listingOrder[sortOrder];
  let queryParams = props.history.location.search;
  const offSetId = useSelector((state) => {
    return state.posts.offset;
  });
  let after = new URLSearchParams(queryParams).get("after");
  let before = new URLSearchParams(queryParams).get("before");
  let query = (after && "after") || (before && "before");
  let id = after || before;

  let postsToDisplay;
  if (currentIds) {
    postsToDisplay = currentIds.map((id) => {
      return allPosts[id];
    });
  }

  const bottomRef = useCallback(
    (node) => {
      const options = {
        threshold: [0],
      };
      let shouldFetch = true;
      var observer = new IntersectionObserver(function (entries, observer) {
        if (entries[0].intersectionRatio > 0 && shouldFetch && offSetId) {
          observer.disconnect();
          dispatch(nextPage(offSetId, params)).then((status) => {
            shouldFetch = false;
            if (status === "completed") {
              observer.observe(node);
            }
          });
        }
      }, options);
      if (postsToDisplay.length > 0 && node && params.sort !== "post") {
        observer.observe(node);
      } else {
        observer.disconnect();
      }
    },
    [offSetId, postsToDisplay]
  );
  useEffect(() => {
    const splitUrl = location.pathname.split("/");
  }, []);
  useEffect(() => {
    const splitUrl = location.pathname.split("/");

    if (params.sort === "post" && dataLoaded === false) {
      dispatch(fetchSinglePost(splitUrl[2])).catch((err) => {});
      // dispatch(fetchPosts(query, id, params.sort === "post" ? null : params));
    } else if (dataLoaded === false) {
      dispatch(
        fetchPosts(query, id, params.sort === "post" ? null : params)
      ).then((data) => {
        if (data.length > 0) {
          setDataLoaded(true);
        }
      });
    }
  }, [params.sort]);
  let listing = listingOrder[sortOrder];
  const handlePostType = (type) => {
    if (!loggedIn) {
      props.handleShowLogin();
    }
    dispatch(newPostSubmissionType(type));
    dispatch(submitPostAttempt());
  };
  if (!listing) {
    return <div></div>;
  }
  return (
    <>
      <div
        className={`home-wrapper ${checkDisplay === "dark" ? "dark-mode" : ""}`}
      >
        {props.showSignup ? <Signup /> : null}
        <div
          className={`new-post-container ${
            checkDisplay === "dark" ? "dark-mode-border" : ""
          }`}
        >
          <Link to="">
            <img
              className={`new-post-profile-image ${
                checkDisplay === "dark" ? "dark-mode-border" : ""
              }`}
              src={defaultPic}
              alt=""
            />
          </Link>
          <Link
            onClick={() => handlePostType("post")}
            to={loggedIn ? "/new-post" : ""}
            className="new-post-input-container"
          >
            <input
              placeholder="Create Post"
              className={`new-post-input ${
                checkDisplay === "dark" ? "dark-mode-border" : ""
              }`}
              type="text"
            />
          </Link>
          <Link
            onClick={() => handlePostType("media")}
            to={loggedIn ? "/new-post?media=true" : ""}
          >
            <img className="post-option" src={imagePost} alt="" />
          </Link>
          <Link
            onClick={() => handlePostType("link")}
            to={loggedIn ? "/new-post?link=true" : ""}
          >
            <img className="post-option" src={linkPost} alt="" />
          </Link>
        </div>
        <div
          className={`categories-container ${
            checkDisplay === "dark" ? "dark-mode-border" : ""
          }`}
        >
          <Link
            to="/hot"
            className={`${checkDisplay === "dark" ? "dark-mode-border" : ""}`}
            onClick={() =>
              dispatch(fetchPosts(query, id, { sort: "hot" }, "click"))
            }
          >
            Hot
          </Link>
          <Link
            className={`${checkDisplay === "dark" ? "dark-mode-border" : ""}`}
            to="/new"
            onClick={() =>
              dispatch(fetchPosts(query, id, { sort: "new" }, "click"))
            }
          >
            New
          </Link>
          <Link
            className={`${checkDisplay === "dark" ? "dark-mode-border" : ""}`}
            to="/top"
            onClick={() =>
              dispatch(fetchPosts(query, id, { sort: "top" }, "click"))
            }
          >
            Top
          </Link>
        </div>
        <div className={"posts-container"}>
          {postsToDisplay.map((post) => {
            if (post) {
              return <Post history={props} key={post.id} post={post} />;
            }
          })}
          <div className="page-set-container"></div>
        </div>
      </div>
      <div className="loading-container">
        <div
          className={postStatus === "loading" ? "lds-dual-ring" : "inactive"}
        ></div>
      </div>
      <span ref={bottomRef}></span>
    </>
  );
}
export default Home;
