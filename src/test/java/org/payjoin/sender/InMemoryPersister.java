package org.payjoin.sender;

import java.util.ArrayList;
import java.util.List;

final class InMemoryPersister implements Persister {
    private final List<String> lines = new ArrayList<>();

    @Override
    public synchronized void append(String line) {
        lines.add(line);
    }

    @Override
    public synchronized List<String> load() {
        return List.copyOf(lines);
    }
}
