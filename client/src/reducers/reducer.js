import { combineReducers } from "redux";
import {
  CLEAR_ERROR,
  CLEAR_LOGIN_MODAL,
  CURRENT_USER,
  DARK_MODE_DISABLED,
  DARK_MODE_ENABLED,
  DELETE_POST,
  EDIT_POST,
  LOGIN_ERROR,
  LOGIN_REQUEST,
  LOGIN_SUCCESS,
  LOG_OUT,
  NEW_COMMENT_SUCCESS,
  NEW_POST_REQUEST,
  NEW_POST_SUCCESS,
  NEW_REPLY_REQUEST,
  NEW_REPLY_SUCCESS,
  NEXT_PAGE,
  POST_CREATION_CHANGE_SUBMISSION_TYPE,
  PREV_PAGE,
  RECEIVE_COMMENTS,
  RECEIVE_POSTS,
  RECEIVE_SINGLE_POSTS,
  REFRESH_USER,
  REQUEST_POSTS,
  REQUEST_USER_INFO,
  SET_POST_MODAL,
  SIGNUP_ERROR,
  SIGNUP_REQUEST,
  SIGNUP_SUCCESS,
  SORT_POSTS,
  SPLICED_POST,
  UNAUTHORIZED_ERROR,
  VOTE_CAST,
} from "../types";
function combineArrays(arr1, arr2) {
  let combined = arr1.concat(arr2);
  let set = new Set(combined);
  return [...set];
}
function addComment(state, action) {
  return {
    ...state,
    byId: {
      ...state.byId,
      [action.postId]: {
        ...state.byId[action.postId],
        comments: [
          ...state.byId[action.postId].comments,
          action.savedComment.id,
        ],
      },
    },
  };
}
function changePostPoint(state, action) {
  const { postId } = action;
  const { point } = action;
  const { currentVoteState } = action;
  const post = state.byId[postId];
  if (action.commentId) {
    return state;
  } else {
    if (currentVoteState === 1 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: 0,
            voteTotal: state.byId[postId].voteTotal - 1,
          },
        },
      };
    }
    if (currentVoteState === 0 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: 1,
            voteTotal: state.byId[postId].voteTotal + 1,
          },
        },
      };
    }
    if (currentVoteState === 1 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: -1,
            voteTotal: state.byId[postId].voteTotal - 2,
          },
        },
      };
    }
    if (currentVoteState === 0 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: -1,
            voteTotal: state.byId[postId].voteTotal - 1,
          },
        },
      };
    }
    if (currentVoteState === -1 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: 0,
            voteTotal: state.byId[postId].voteTotal + 1,
          },
        },
      };
    }
    if (currentVoteState === -1 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [postId]: {
            ...post,
            voteState: 1,
            voteTotal: state.byId[postId].voteTotal + 2,
          },
        },
      };
    }
  }
}
function handlePostSubmission(state, action) {
  const { post, id } = action;
  return {
    ...state,
    byId: {
      ...state.byId,
      [id]: post,
    },
    allIds: [...state.allIds, id],
    submitting: false,
    createdPosts: {
      ...state.createdPosts,
      [id]: post,
    },
    submitted: true,
    reRouteId: id,
  };
}
function editPostReduce(state, action) {
  const { postId, content } = action;
  const post = state.byId[postId];
  return {
    ...state,
    byId: {
      ...state.byId,
      [postId]: {
        ...post,
        content: content,
      },
    },
  };
}
function handlePreviousPage(state, action) {
  let allIds = state.allIds;
  let incomingIds = action.normalizedData.result;
  let set = new Set(incomingIds.concat(allIds));
  return {
    ...state,
    isFetching: false,
    byId: {
      ...state.byId,
      ...action.normalizedData.entities.posts,
    },
    status: "succeeded",
    allIds: [...set],
  };
}
function handleNextPage(state, action) {
  let allIds = state.allIds;
  let incomingIds = action.normalizedData.result;
  let set = new Set(allIds.concat(incomingIds));
  return {
    ...state,
    isFetching: false,
    byId: {
      ...state.byId,
      ...action.normalizedData.entities.posts,
    },
    offset: action.offset,
    status: "succeeded",
    allIds: [...set],
  };
}
function setListings(state, action, prev) {
  return {
    ...state,
    status: "completed",
    sortOrder: action.sort,
    listingOrder: {
      ...state.listingOrder,
      [action.sort]: combineArrays(
        state.listingOrder[action.sort] ? state.listingOrder[action.sort] : [],
        action.normalizedData.result
      ),
    },
  };
}
function listings(
  state = {
    sortOrder: "default",
    listingOrder: {},
    status: "idle",
  },
  action
) {
  switch (action.type) {
    case SORT_POSTS:
      return setListings(state, action);
    case REQUEST_POSTS:
      return action.e
        ? Object.assign({}, state, {
            status: "loading",
          })
        : state;
    case DELETE_POST:
      const filteredPosts = state.listingOrder[state.sortOrder].filter((id) => {
        return id !== action.postId;
      });
      return {
        ...state,
        listingOrder: {
          ...state.listingOrder,
          [state.sortOrder]: [...filteredPosts],
        },
      };
    case PREV_PAGE:
      return setListings(state, action, "prev");
    case NEXT_PAGE:
      return setListings(state, action);
    case RECEIVE_POSTS:
      return setListings(state, action);
    default:
      return state;
  }
}
function receievePosts(state, action) {
  let allIds = state.allIds;
  let incomingIds = action.normalizedData.result;
  let set = new Set(allIds.concat(incomingIds));
  return {
    ...state,
    isFetching: false,
    byId: {
      ...state.byId,
      ...action.normalizedData.entities.posts,
    },
    offset: action.offset,
    status: "completed",
    allIds: [...set],
  };
}
function recieveSinglePost(state, action) {
  let allIds = state.allIds;
  let incomingIds = action.normalizedData.result;
  let set = new Set(allIds.concat(incomingIds));
  return {
    ...state,
    isFetching: false,
    byId: {
      ...state.byId,
      ...action.normalizedData.entities.posts,
    },
    offset: action.offset,
    status: "completed",
    allIds: [...set],
  };
}
export function posts(
  state = {
    isFetching: false,
    byId: {},
    allIds: [],
    offset: null,
    submitted: false,
    err: null,
    createdPosts: {},
    submitting: false,
    reRouteId: null,
    status: "idle",
    firstId: "",
    lastId: "",
  },
  action
) {
  switch (action.type) {
    case RECEIVE_COMMENTS:
      const postid = action.postid;
      return Object.assign({}, state, {
        byId: {
          ...state.byId,
          [postid]: {
            ...state.byId[postid],
            comments: action.commentids || [],
          },
        },
      });
    case NEW_REPLY_SUCCESS:
      const newIndex = action.parentIndex + 1;

      const currPostid = state.byId[action.postId];

      const newArray = [...currPostid.comments];
      newArray.splice(newIndex, 0, action.reply.id);

      return Object.assign({}, state, {
        byId: {
          ...state.byId,
          [action.postId]: {
            ...state.byId[action.postId],
            comments: newArray || [],
          },
        },
      });
    case SORT_POSTS:
      return Object.assign({}, state, {
        status: "idle",
        offset: action.offset,
      });
    case PREV_PAGE:
      return handlePreviousPage(state, action);
    case NEXT_PAGE:
      return handleNextPage(state, action);
    case REQUEST_POSTS:
      return Object.assign({}, state, {
        isFetching: true,
        status: "loading",
      });
    case SPLICED_POST:
      return Object.assign({}, state, {
        byId: action.newObj,
        allIds: action.splicedArray,
        createdPosts: {},
      });
    case RECEIVE_SINGLE_POSTS:
      return receievePosts(state, action);
    case RECEIVE_POSTS:
      return receievePosts(state, action);
    case VOTE_CAST:
      return changePostPoint(state, action);
    case DELETE_POST:
      const allIds = state.allIds;
      const filteredPosts = allIds.filter((id) => {
        return id !== action.postId;
      });
      return Object.assign({}, state, {
        allIds: filteredPosts,
      });
    case NEW_COMMENT_SUCCESS:
      return addComment(state, action);
    case NEW_POST_REQUEST:
      return Object.assign({}, state, {
        submitted: false,
        submitting: true,
        reRouteId: "",
      });
    case EDIT_POST:
      return editPostReduce(state, action);
    case NEW_POST_SUCCESS:
      return handlePostSubmission(state, action);
    default:
      return state;
  }
}
function setPostModal(state, action) {
  const { post } = action;
  return {
    ...state,
    post,
  };
}
function currentModal(
  state = {
    post: {},
  },
  action
) {
  switch (action.type) {
    case SET_POST_MODAL:
      return setPostModal(state, action);
    case NEW_POST_SUCCESS:
      return Object.assign({}, state, {
        post: action.post,
      });
    default:
      return state;
  }
}
function addCommentEntry(state, action) {
  const { savedComment } = action;
  return {
    ...state,
    byId: {
      ...state.byId,
      [action.savedComment.id]: {
        ...state.byId[savedComment.id],
        ...action.savedComment,
      },
    },
  };
}
function changeCommentPoint(state, action) {
  if (action.commentId) {
    const { commentId } = action;
    const { point } = action;
    const { currentVoteState } = action;
    const comment = state.byId[commentId];
    if (currentVoteState === 1 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: 0,
            voteTotal: state.byId[commentId].voteTotal - 1,
          },
        },
      };
    }
    if (currentVoteState === 0 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: 1,
            voteTotal: state.byId[commentId].voteTotal + 1,
          },
        },
      };
    }
    if (currentVoteState === 1 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: -1,
            voteTotal: state.byId[commentId].voteTotal - 2,
          },
        },
      };
    }
    if (currentVoteState === 0 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: -1,
            voteTotal: state.byId[commentId].voteTotal - 1,
          },
        },
      };
    }
    if (currentVoteState === -1 && point === -1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: 0,
            voteTotal: state.byId[commentId].voteTotal + 1,
          },
        },
      };
    }
    if (currentVoteState === -1 && point === 1) {
      return {
        ...state,
        byId: {
          ...state.byId,
          [commentId]: {
            ...comment,
            voteState: 1,
            voteTotal: state.byId[commentId].voteTotal + 2,
          },
        },
      };
    }
  } else {
    return state;
  }
}
const newReply = (state, action) => {
  return {
    ...state,
    byId: {
      ...state.byId,
      [action.reply.id]: action.reply,
    },
  };
};
function comments(
  state = {
    byId: {},
    allId: [],
  },
  action
) {
  switch (action.type) {
    case RECEIVE_COMMENTS: {
      return Object.assign({}, state, {
        byId: {
          ...state.byId,
          ...action.comments,
        },
      });
    }

    case RECEIVE_SINGLE_POSTS: {
      return Object.assign({}, state, {
        byId: {
          ...state.byId,
          ...action.normalizedData.entities.comments,
        },
      });
    }
    case RECEIVE_POSTS: {
      return Object.assign({}, state, {
        byId: {
          ...state.byId,
          ...action.normalizedData.entities.comments,
        },
      });
    }
    case NEW_REPLY_SUCCESS:
      return newReply(state, action);
    case VOTE_CAST:
      return changeCommentPoint(state, action);
    case NEW_COMMENT_SUCCESS:
      return addCommentEntry(state, action);
    case NEW_REPLY_REQUEST:
      return Object.assign({}, state, {});
    default:
      return state;
  }
}
function changeNewSubmissionType(
  state = {
    submissionType: "",
  },
  action
) {
  switch (action.type) {
    case POST_CREATION_CHANGE_SUBMISSION_TYPE:
      return Object.assign({}, state, {
        submissionType: action.postType,
      });
    default:
      return state;
  }
}
function signup(
  state = {
    isSigningUp: false,
    isSignedUp: false,
    err: null,
    passwordError: null,
  },
  action
) {
  const { passwordError } = action;
  switch (action.type) {
    case SIGNUP_REQUEST:
      return Object.assign({}, state, {
        err: null,
        passwordError: null,
      });
    case SIGNUP_SUCCESS:
      return Object.assign({}, state, {
        isSignedUp: true,
        isSigningUp: false,
        err: null,
        passwordError: null,
      });
    case CLEAR_ERROR:
      return Object.assign({}, state, {
        err: null,
      });
    case SIGNUP_ERROR:
      return Object.assign({}, state, {
        err: action.error,
        passwordError,
      });
    default:
      return state;
  }
}
function login(
  state = {
    isLoggingIn: false,
    isLoggedIn: false,
    err: null,
    fetching: false,
  },
  action
) {
  switch (action.type) {
    case REQUEST_USER_INFO:
      return Object.assign({}, state, {
        isLoggedIn: true,
        fetching: true,
      });
    case CURRENT_USER:
      return Object.assign({}, state, {
        fetching: false,
      });
    case UNAUTHORIZED_ERROR:
      return Object.assign({}, state, {
        err: "Username or Password do not match",
      });
    case CLEAR_LOGIN_MODAL:
      return Object.assign({}, state, {
        err: null,
      });
    case LOGIN_REQUEST:
      return Object.assign({}, state, {
        isLoggingIn: true,
        isLoggedIn: false,
      });
    case LOGIN_SUCCESS:
      return Object.assign({}, state, {
        isLoggingIn: false,
        isLoggedIn: true,
      });
    case LOG_OUT:
      return Object.assign({}, state, {
        isLoggingIn: false,
        isLoggedIn: false,
      });
    case LOGIN_ERROR:
      return Object.assign({}, state, {
        isLoggingIn: false,
        isLoggedIn: false,
      });
    default:
      return state;
  }
}
function currentUser(
  state = {
    username: "",
    id: "",
    err: null,
  },
  action
) {
  switch (action.type) {
    case LOG_OUT:
      return Object.assign({}, state, {
        username: null,
        id: null,
      });
    case REFRESH_USER:
      return Object.assign({}, state, {
        username: action.userInfo.username,
        id: action.userInfo.id,
      });
    case LOGIN_SUCCESS:
      return Object.assign({}, state, {
        username: action.username,
        id: action.id,
      });
    case CURRENT_USER:
      return Object.assign({}, state, {
        isLoggedIn: true,
        username: action.username,
        id: action.user,
      });
    default:
      return state;
  }
}
export function display(
  state = {
    display: "default",
  },
  action
) {
  switch (action.type) {
    case DARK_MODE_ENABLED:
      return Object.assign({}, state, {
        display: "dark",
      });
    case DARK_MODE_DISABLED:
      return Object.assign({}, state, {
        display: "default",
      });
    default:
      return state;
  }
}
const rootReducer = combineReducers({
  comments,
  display,
  currentModal,
  changeNewSubmissionType,
  posts,
  login,
  signup,
  currentUser,
  listings,
});

export default rootReducer;
