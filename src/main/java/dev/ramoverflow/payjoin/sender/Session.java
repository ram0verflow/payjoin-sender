package dev.ramoverflow.payjoin.sender;

/**
 * A sender session restored from its log, or the proposal that closed it.
 * {@link Proposal} is returned only after the sender checklist passes.
 */
public sealed interface Session permits Post, Poll, Proposal {}
