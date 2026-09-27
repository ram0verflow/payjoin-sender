package org.payjoin.sender;

/**
 * A sender session restored from its log, or the proposal that closed it.
 * {@link Proposal} is not ready to sign until the BIP 78 sender checklist exists.
 */
public sealed interface Session permits Post, Poll, Proposal {}
