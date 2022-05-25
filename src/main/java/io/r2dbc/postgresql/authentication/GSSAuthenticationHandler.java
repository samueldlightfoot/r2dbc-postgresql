/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.r2dbc.postgresql.authentication;

import io.r2dbc.postgresql.message.backend.AuthenticationGSS;
import io.r2dbc.postgresql.message.backend.AuthenticationGSSContinue;
import io.r2dbc.postgresql.message.backend.AuthenticationMessage;
import io.r2dbc.postgresql.message.frontend.FrontendMessage;
import io.r2dbc.postgresql.message.frontend.GSSAuthenticationToken;
import io.r2dbc.postgresql.util.Assert;
import org.ietf.jgss.*;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * An implementation of {@link AuthenticationHandler} that handles GSS authentication.
 */
public final class GSSAuthenticationHandler implements AuthenticationHandler {

	private static final String jaasApplicationName = "pdjdbc";
	private static final String kerberosServerName = "cockroachdb";

	private final String user;
	private final char[] pass;
	private final String host;
	private final AtomicReference<GSSContext> gssContext = new AtomicReference<>();
	private final AtomicReference<Subject> subject = new AtomicReference<>();

	public GSSAuthenticationHandler(String user, @Nullable CharSequence pass, String host) {
		this.user = Assert.requireNonNull(user, "user must not be null");
		this.pass = pass == null ? null : pass.toString().toCharArray();
		this.host = Assert.requireNonNull(host, "host must not be null");
	}

	public static boolean supports(final AuthenticationMessage message) {
		return message instanceof AuthenticationGSS;
	}

	@Override
	public FrontendMessage handle(AuthenticationMessage message) {
		Assert.requireNonNull(message, "message must not be null");

		try {
			if (message instanceof AuthenticationGSS) {
				return handleAuthenticationGss();
			}

			if (message instanceof AuthenticationGSSContinue) {
				return handleAuthenticationGssContinue((AuthenticationGSSContinue) message);
			}
		} catch (Exception exc) {
			throw new RuntimeException("GSS Authentication failed", exc);
		}

		throw new IllegalArgumentException(
			String.format("Cannot handle %s message", message.getClass().getSimpleName()));
	}

	private FrontendMessage handleAuthenticationGssContinue(
		AuthenticationGSSContinue authenticationGSSContinue) {
		Subject subject = this.subject.get();
		GSSContext gssContext = this.gssContext.get();

		byte[] outToken = Subject.doAs(subject,
			new GssContinueAction(authenticationGSSContinue, gssContext));

		return new GSSAuthenticationToken(outToken);
	}

	private FrontendMessage handleAuthenticationGss() throws LoginException {
		boolean performLogin = true;

		// Check if we can get credential from Subject to avoid login
		Subject subject = Subject.getSubject(AccessController.getContext());
		if (subject != null) {
			Set<GSSCredential> gssCredentials = subject.getPrivateCredentials(GSSCredential.class);
			if (!gssCredentials.isEmpty()) {
				performLogin = false;
			}
		}

		if (performLogin) {
			LoginContext loginContext = new LoginContext(jaasApplicationName,
				new GSSCallbackHandler(user, pass));
			loginContext.login();
			subject = loginContext.getSubject();
			this.subject.set(subject);
		}

		GssInitialAction action = new GssInitialAction(host, user, kerberosServerName, subject);
		Tuple2<GSSContext, byte[]> result = Subject.doAs(subject, action);

		gssContext.compareAndSet(null, result.getT1());

		return new GSSAuthenticationToken(result.getT2());
	}

	private static class GSSCallbackHandler implements CallbackHandler {

		private final String user;
		private final char[] pass;

		GSSCallbackHandler(String user, char[] pass) {
			this.user = user;
			this.pass = pass;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (Callback callback : callbacks) {
				if (callback instanceof NameCallback) {
					NameCallback nc = (NameCallback) callback;
					nc.setName(user);
				} else if (callback instanceof PasswordCallback) {
					PasswordCallback pc = (PasswordCallback) callback;
					pc.setPassword(pass);
				}
			}
		}
	}


	private static final class GssContinueAction implements PrivilegedAction<byte[]> {

		private final AuthenticationGSSContinue authenticationGSSContinue;
		private final GSSContext gssContext;

		GssContinueAction(AuthenticationGSSContinue authenticationGSSContinue,
			GSSContext gssContext) {
			this.authenticationGSSContinue = authenticationGSSContinue;
			this.gssContext = gssContext;
		}

		@Override
		public byte[] run() {
			byte[] inToken = authenticationGSSContinue.getAuthenticationData().array();
			try {
				return gssContext.initSecContext(inToken, 0, inToken.length);
			} catch (GSSException exc) {
				throw new RuntimeException(exc);
			}
		}

	}

	private static final class GssInitialAction implements
		PrivilegedAction<Tuple2<GSSContext, byte[]>> {

		// non-spnego
		private static final String OID = "1.2.840.113554.1.2.2";

		private final String host;
		private final String user;
		private final String kerberosServerName;
		private final Subject subject;

		GssInitialAction(String host, String user, String kerberosServerName, Subject subject) {
			this.host = host;
			this.user = user;
			this.kerberosServerName = kerberosServerName;
			this.subject = subject;
		}

		@Override
		public Tuple2<GSSContext, byte[]> run() {
			try {
				GSSContext context = createGssContext();
				byte[] outToken = context.initSecContext(new byte[0], 0, 0);
				return Tuples.of(context, outToken);
			} catch (GSSException exc) {
				throw new RuntimeException(exc);
			}
		}

		private GSSContext createGssContext() throws GSSException {
			GSSManager manager = GSSManager.getInstance();
			Oid[] desiredMechs = new Oid[]{new Oid(OID)};

			// Try to get credential from subject first.
			GSSCredential gssCredential = null;
			Set<GSSCredential> gssCreds = subject.getPrivateCredentials(GSSCredential.class);
			if (!gssCreds.isEmpty()) {
				gssCredential = gssCreds.iterator().next();
			}

			// If failed to get credential from subject, then call createCredential to create one.
			final GSSCredential clientCredential;
			if (gssCredential == null) {
				String principalName = this.user;
				Set<Principal> principals = subject.getPrincipals();
				Iterator<Principal> principalIterator = principals.iterator();

				Principal principal;
				if (principalIterator.hasNext()) {
					principal = principalIterator.next();
					principalName = principal.getName();
				}

				GSSName clientName = manager.createName(principalName, GSSName.NT_USER_NAME);
				clientCredential = manager.createCredential(clientName, 8 * 3600, desiredMechs,
					GSSCredential.INITIATE_ONLY);
			} else {
				clientCredential = gssCredential;
			}

			GSSName serverName =
				manager.createName(kerberosServerName + "@" + host, GSSName.NT_HOSTBASED_SERVICE);

			GSSContext gssContext =
				manager.createContext(serverName, desiredMechs[0], clientCredential,
					GSSContext.DEFAULT_LIFETIME);
			gssContext.requestMutualAuth(true);
			return gssContext;
		}
	}

}
