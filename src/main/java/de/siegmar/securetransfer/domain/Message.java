/*
 * Copyright 2017 Oliver Siegmar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.siegmar.securetransfer.domain;

import java.time.Instant;
import java.util.Objects;

public class Message {

    private String id;
    private Instant expiration;

    public Message() {
    }

    public Message(final String id, final Instant expiration) {
        this.id = Objects.requireNonNull(id);
        this.expiration = Objects.requireNonNull(expiration);
    }

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public Instant getExpiration() {
        return expiration;
    }

    public void setExpiration(final Instant expiration) {
        this.expiration = expiration;
    }

}
