import axios from "axios";
import expect from "expect"; // You can use any testing library
import { createStore } from "redux";
import configureMockStore from "redux-mock-store";
import thunk from "redux-thunk";
import rootReducer, { posts } from "../reducers/reducer";
import * as types from "../types";
import * as actions from "./postActions";
const middlewares = [thunk];
const store = createStore(rootReducer);
const mockStore = configureMockStore(middlewares);
jest.mock("axios");
describe("async actions", () => {
  it("creates FETCH_TODOS_SUCCESS when fetching todos has been done", () => {
    const expectedActions = [
      { type: types.REQUEST_POSTS },
      {
        type: types.RECEIVE_POSTS,
        normalizedData: {
          entities: {},
          result: [],
        },
        offset: undefined,
        sort: "default",
      },
    ];
    const store = mockStore({ todos: [] });
    const users = { posts: [] };
    const resp = { data: users };

    axios.get.mockResolvedValue(resp);
    return store.dispatch(actions.fetchPosts()).then((data) => {
      // return of async actions
      expect(store.getActions()).toEqual(expectedActions);
    });
  });
});
describe("post reducer", () => {
  it("should return the initial state", () => {
    expect(rootReducer(undefined, {})).toEqual({
      comments: { byId: {}, allId: [] },
      display: { display: "default" },
      currentModal: { post: {} },
      changeNewSubmissionType: { submissionType: "" },
      posts: {
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
      login: {
        isLoggingIn: false,
        isLoggedIn: false,
        err: null,
        fetching: false,
      },
      signup: {
        isSigningUp: false,
        isSignedUp: false,
        err: null,
        passwordError: null,
      },
      currentUser: { username: "", id: "", err: null },
      listings: { sortOrder: "default", listingOrder: {}, status: "idle" },
    });
  });
});
test("should create Post", () => {
  const newPost = {
    upVotes: ["5fb6f704cb32823038271af4"],
    downVotes: [],
    voteTotal: 1,
    hotScore: 10754.9874292,
    topScore: 1618002.437314,
    id: "6070c205de1d4d31e4f69e4a",
    title: "r",
    content: "r",
    createdAt: "2021-04-09T21:07:17.314Z",
    author: "5fb6f704cb32823038271af4",
    comments: [],
    voteState: 1,
    newPost: true,
  };
  expect(
    rootReducer(undefined, {
      type: types.NEW_POST_SUCCESS,
      post: {
        ...newPost,
      },
      id: "6070c205de1d4d31e4f69e4a",
    })
  ).toEqual({
    ...rootReducer(undefined, {}),
    currentModal: {
      post: {
        ...newPost,
      },
    },
    posts: {
      ...rootReducer(undefined, {}).posts,
      byId: {
        "6070c205de1d4d31e4f69e4a": {
          ...newPost,
        },
      },
      allIds: ["6070c205de1d4d31e4f69e4a"],
      submitted: true,
      createdPosts: {
        "6070c205de1d4d31e4f69e4a": {
          ...newPost,
        },
      },
      submitting: false,
      reRouteId: "6070c205de1d4d31e4f69e4a",
    },
  });
});
test("should increase point with an upvote", () => {
  const expectedState = {
    byId: {
      "6070edebde1d4d31e4f69e4c": {
        voteState: 1,
        voteTotal: 1,
      },
    },
  };

  expect(
    posts(
      {
        byId: {
          "6070edebde1d4d31e4f69e4c": {
            voteState: 0,
            voteTotal: 0,
          },
        },
      },
      {
        type: "VOTE_CAST",
        postId: "6070edebde1d4d31e4f69e4c",
        point: 1,
        currentVoteState: 0,
      }
    )
  ).toEqual(expectedState);
});
test("should decrease point with an upvote", () => {
  const expectedState = {
    byId: {
      "6070edebde1d4d31e4f69e4c": {
        voteState: 0,
        voteTotal: 0,
      },
    },
  };

  expect(
    posts(
      {
        byId: {
          "6070edebde1d4d31e4f69e4c": {
            voteState: 1,
            voteTotal: 1,
          },
        },
      },
      {
        type: "VOTE_CAST",
        postId: "6070edebde1d4d31e4f69e4c",
        point: 1,
        currentVoteState: 1,
      }
    )
  ).toEqual(expectedState);
});
test("should decrease point with a downvote", () => {
  const expectedState = {
    byId: {
      "6070edebde1d4d31e4f69e4c": {
        voteState: -1,
        voteTotal: 9,
      },
    },
  };

  expect(
    posts(
      {
        byId: {
          "6070edebde1d4d31e4f69e4c": {
            voteState: 0,
            voteTotal: 10,
          },
        },
      },
      {
        type: "VOTE_CAST",
        postId: "6070edebde1d4d31e4f69e4c",
        point: -1,
        currentVoteState: 0,
      }
    )
  ).toEqual(expectedState);
});
test("should increase point with a downvote", () => {
  const expectedState = {
    byId: {
      "6070edebde1d4d31e4f69e4c": {
        voteState: 0,
        voteTotal: 11,
      },
    },
  };

  expect(
    posts(
      {
        byId: {
          "6070edebde1d4d31e4f69e4c": {
            voteState: -1,
            voteTotal: 10,
          },
        },
      },
      {
        type: "VOTE_CAST",
        postId: "6070edebde1d4d31e4f69e4c",
        point: -1,
        currentVoteState: -1,
      }
    )
  ).toEqual(expectedState);
});
test("should add comment", () => {
  const savedComment = {
    id: "60710cd1de1d4d31e4f69e71",
  };
  const expectedState = {
    ...rootReducer(
      {
        posts: {
          byId: {
            "60564734c8c4821840e65bce": {
              comments: ["60710cd1de1d4d31e4f69e71"],
            },
          },
        },
        comments: {
          byId: {
            "60710cd1de1d4d31e4f69e71": savedComment,
          },
        },
      },
      {}
    ),
  };

  expect(
    rootReducer(
      {
        posts: {
          byId: {
            "60564734c8c4821840e65bce": {
              comments: [],
            },
          },
        },
        comments: {
          byId: {},
        },
      },

      {
        type: "NEW_COMMENT_SUCCESS",
        postId: "60564734c8c4821840e65bce",

        savedComment,
      }
    )
  ).toEqual(expectedState);
});
test("should add reply", () => {
  const savedComment = {
    id: "12345",
    comments: [],
  };

  const expectedState = {
    ...rootReducer(
      {
        comments: {
          byId: {
            "607109f0de1d4d31e4f69e5b": {
              comments: ["12345"],
            },
            [savedComment.id]: {
              comments: [],
              id: "12345",
            },
          },
        },
      },
      {}
    ),
  };

  expect(
    rootReducer(
      {
        comments: {
          byId: {
            "607109f0de1d4d31e4f69e5b": {
              comments: [],
            },
          },
        },
      },

      {
        type: "NEW_REPLY_SUCCESS",
        postId: "60564734c8c4821840e65bce",
        commentId: "607109f0de1d4d31e4f69e5b",
        reply: {
          ...savedComment,
        },
      }
    )
  ).toEqual(expectedState);
});
