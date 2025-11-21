import { describe, it, expect } from "vitest";
import {
  renderClickHandler,
  renderState,
  renderTransition,
  StateNode,
  TransitionEdge,
} from "./mermaid.js";

describe("renderState", () => {
  it("should render a page state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "page",
          pageId: "test-page",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST[TEST\ntest-page]:::page");
  });

  it("should render a cri state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "cri",
          criId: "test-cri",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST([TEST\ntest-cri]):::cri");
  });

  it("should render a cri state with context", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "cri",
          criId: "test-cri",
          context: "test-context",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual(
      "    TEST([TEST\ntest-cri\n context: test-context]):::cri",
    );
  });

  it("should render a process state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "process",
          lambda: "test-lambda",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST(TEST\ntest-lambda):::process");
  });

  it("should render a journey transition state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "journeyTransition",
          targetJourney: "TEST_JOURNEY",
          targetState: "TEST_STATE",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual(
      "    TEST(TEST_JOURNEY\nTEST_STATE):::journey_transition",
    );
  });

  it("should render a failed journey transition state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "journeyTransition",
          targetJourney: "FAILED",
          targetState: "FAILED",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST(FAILED\nFAILED):::error_transition");
  });

  it("should render a nested journey state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "nestedJourney",
          nestedJourney: "TEST_JOURNEY",
        },
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST(TEST\nTEST_JOURNEY):::nested_journey");
  });

  it("should render a synthetic entry state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        entryEvent: "test-entry",
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST[ENTRY\ntest-entry]:::other");
  });

  it("should render a synthetic exit state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        exitEvent: "test-exit",
      },
    };

    // Act
    const actual = renderState(state);

    // Assert
    expect(actual).toEqual("    TEST[EXIT\ntest-exit]:::other");
  });
});

describe("renderClickHandler", () => {
  it("should render a click handler for a standard state", () => {
    // Arrange
    const state: StateNode = {
      name: "TEST",
      definition: {
        response: {
          type: "page",
          pageId: "test-page",
        },
      },
    };

    // Act
    const actual = renderClickHandler(state);

    // Assert
    const expectedArg = btoa(
      JSON.stringify({
        type: "page",
        pageId: "test-page",
      }),
    );
    expect(actual).toEqual(
      `    click TEST call onStateClick("TEST", ${expectedArg})`,
    );
  });
});

describe("renderTransition", () => {
  it("should render a standard transition", () => {
    // Arrange
    const transition: TransitionEdge = {
      sourceState: "SOURCE",
      targetState: "TARGET",
      transitionEvents: [{ eventName: "test-event" }],
    };

    // Act
    const actual = renderTransition(transition);

    // Assert
    expect(actual).toEqual(
      '    SOURCE SOURCE-TARGET@-->|<p class="defaultEdgeLabel">test-event</p>|TARGET',
    );
  });

  it("should render a transition with journeyContext", () => {
    // Arrange
    const transition: TransitionEdge = {
      sourceState: "SOURCE",
      targetState: "TARGET",
      transitionEvents: [
        { eventName: "test-event", journeyContext: "test-context" },
      ],
    };

    // Act
    const actual = renderTransition(transition);

    // Assert
    expect(actual).toEqual(
      '    SOURCE SOURCE-TARGET@-->|<p class="defaultEdgeLabel journeyCtxTransition">test-event - journeyContext: test-context</p>|TARGET',
    );
  });

  it("should render a transition with a mitigation", () => {
    // Arrange
    const transition: TransitionEdge = {
      sourceState: "SOURCE",
      targetState: "TARGET",
      transitionEvents: [
        { eventName: "test-event", mitigation: "test-mitigation" },
      ],
    };

    // Act
    const actual = renderTransition(transition);

    // Assert
    expect(actual).toEqual(
      '    SOURCE SOURCE-TARGET@-->|<p class="defaultEdgeLabel mitigationTransition">test-event - mitigation: test-mitigation</p>|TARGET',
    );
  });

  it("should render multiple transitions", () => {
    // Arrange
    const transition: TransitionEdge = {
      sourceState: "SOURCE",
      targetState: "TARGET",
      transitionEvents: [
        { eventName: "test-event" },
        { eventName: "test-event", journeyContext: "test-context" },
        { eventName: "test-event", mitigation: "test-mitigation" },
      ],
    };

    // Act
    const actual = renderTransition(transition);

    // Assert
    expect(actual).toEqual(
      '    SOURCE SOURCE-TARGET@-->|<p class="defaultEdgeLabel">test-event</p>\n<p class="defaultEdgeLabel journeyCtxTransition">test-event - journeyContext: test-context</p>\n<p class="defaultEdgeLabel mitigationTransition">test-event - mitigation: test-mitigation</p>|TARGET',
    );
  });
});
