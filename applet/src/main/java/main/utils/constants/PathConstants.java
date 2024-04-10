package main.utils.constants;

import java.util.Objects;

public class PathConstants {
    public static final String SECRET_NAMES = Objects.requireNonNull(Thread.currentThread()
                    .getContextClassLoader()
                    .getResource("secrets.txt"))
            .getPath();
}
