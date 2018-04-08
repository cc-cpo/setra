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

package de.siegmar.securetransfer.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.OptionalInt;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadBase;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.propertyeditors.StringTrimmerEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.DataBinder;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.method.annotation.MvcUriComponentsBuilder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.google.common.base.Strings;
import com.google.common.hash.HashCode;

import de.siegmar.securetransfer.config.SecureTransferConfiguration;
import de.siegmar.securetransfer.controller.dto.AuthorizationChallengeCommand;
import de.siegmar.securetransfer.controller.dto.EncryptMessageCommand;
import de.siegmar.securetransfer.domain.KeyIv;
import de.siegmar.securetransfer.domain.SecretFile;
import de.siegmar.securetransfer.domain.SenderMessage;
import de.siegmar.securetransfer.service.GoogleAuthenticatorOTPService;
import de.siegmar.securetransfer.service.MessageSenderService;

@Controller
@RequestMapping("/send")
public class SendController {

    private static final String FORM_SEND_MSG = "send/send_form";
    private static final String FORM_MSG_STATUS = "send/message_status";
    private static final String accessTokenSecretKey = "EoS2phish3Ac7taingaCaine";

    private final MessageSenderService messageService;
    private final Validator validator;
    private final SecureTransferConfiguration config;
    private final GoogleAuthenticatorOTPService otpService;

    // TODO
    private final boolean enableTOTPChallenge = true;

    @Autowired
    public SendController(final MessageSenderService messageService,
                          final @Qualifier("mvcValidator") Validator validator,
                          final SecureTransferConfiguration config,
                          final GoogleAuthenticatorOTPService otpService) {
        this.messageService = messageService;
        this.validator = validator;
        this.config = config;
        this.otpService = otpService;
    }

    @ModelAttribute
    public void initModel(final Model model) {
        model
            .addAttribute("message_max_length", EncryptMessageCommand.MESSAGE_MAX_LENGTH)
            .addAttribute("password_max_length", EncryptMessageCommand.PASSWORD_MAX_LENGTH)
            .addAttribute("max_expiration", EncryptMessageCommand.MAX_EXPIRATION);

        if (enableTOTPChallenge) {
            model
                .addAttribute("enable_challenge", true);
        }
    }

    // see https://stackoverflow.com/questions/25268000/handling-multiple-forms-spring?rq=1
    @PostMapping(name = "/authorize", params = "authorize")
    public ModelAndView authorize(@ModelAttribute final AuthorizationChallengeCommand command, final Errors errors) {

        System.out.println("CHECK -> code = " + command.getChallengeNumber1());

        final boolean authorized = otpService.checkCode(command.getChallengeNumber1());

        if (!authorized) {
            System.out.println("verification CODE rejected");
            errors.reject(null, "Verification CODE not correct");
            return form(null);
        }

        final String accessToken = createAccessToken();


        return new ModelAndView("redirect:/send?token="+accessToken);
//        return new ModelAndView("redirect:"+FORM_SEND_MSG + "?token="+accessToken);

    }

    /**
     * Display the send form.
     */
    @GetMapping
    public ModelAndView form(@RequestParam(name = "token", required = false) final String accessToken) {
        System.out.println("GET form");
        System.out.println("accessToken = " + accessToken);
        // TODO rework
        final EncryptMessageCommand encryptMessageCommand = new EncryptMessageCommand();
        encryptMessageCommand.setAccessToken(accessToken);
        return new ModelAndView(FORM_SEND_MSG)
            .addObject("command", encryptMessageCommand)
            .addObject("challenge", new AuthorizationChallengeCommand());
    }

    /**
     * Process the send form.
     */
    @PostMapping
    public ModelAndView create(final HttpServletRequest req,
                               final RedirectAttributes redirectAttributes)
        throws IOException, FileUploadException {

        if (!ServletFileUpload.isMultipartContent(req)) {
            throw new IllegalStateException("No multipart request!");
        }

        // Create encryptionKey and initialization vector (IV) to encrypt data
        final KeyIv encryptionKey = messageService.newEncryptionKey();

        // secret shared with receiver using the link - not stored in database
        final String linkSecret = messageService.newRandomId();

        final DataBinder binder = initBinder();

        final List<SecretFile> tmpFiles = handleStream(req, encryptionKey, binder);

        final EncryptMessageCommand command = (EncryptMessageCommand) binder.getTarget();
        final BindingResult errors = binder.getBindingResult();

        if (!errors.hasErrors()
            && command.getMessage() == null
            && (tmpFiles == null || tmpFiles.isEmpty())) {
            errors.reject(null, "Neither message nor files submitted");
        }

        // TODO
        System.out.println("VALIDATE TOKEN " + command.getAccessToken());
        if (enableTOTPChallenge && !validateAccessToken(command.getAccessToken())) {
            errors.reject(null, "Invalid access token");
        }

        if (errors.hasErrors()) {
            return new ModelAndView(FORM_SEND_MSG, binder.getBindingResult().getModel())
                .addObject("challenge", new AuthorizationChallengeCommand());
        }

        final String senderId = messageService.storeMessage(command.getMessage(), tmpFiles,
            encryptionKey, HashCode.fromString(linkSecret).asBytes(), command.getPassword(),
            Instant.now().plus(command.getExpirationDays(), ChronoUnit.DAYS));

        redirectAttributes
            .addFlashAttribute("messageSent", true)
            .addFlashAttribute("message", command.getMessage());

        return
            new ModelAndView("redirect:/send/" + senderId)
            .addObject("linkSecret", linkSecret);
    }


    private String createAccessToken() {
        try {
            return JWT.create()
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(Algorithm.HMAC256(accessTokenSecretKey));
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private boolean validateAccessToken(final String accessToken) {

        try {
            JWT.require(Algorithm.HMAC256(accessTokenSecretKey))
                .acceptExpiresAt(5)
                .build()
                .verify(accessToken);
            return true;
        } catch(final JWTVerificationException tee) {
            return false;
        } catch (IllegalArgumentException | UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }

    }

    private DataBinder initBinder() {
        final DataBinder binder = new DataBinder(new EncryptMessageCommand(), "command");
        binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));
        binder.setValidator(validator);
        return binder;
    }

    private List<SecretFile> handleStream(final HttpServletRequest req,
                                          final KeyIv encryptionKey, final DataBinder binder)
        throws FileUploadException, IOException {

        final BindingResult errors = binder.getBindingResult();

        final MutablePropertyValues propertyValues = new MutablePropertyValues();
        final List<SecretFile> tmpFiles = new ArrayList<>();

        @SuppressWarnings("checkstyle:anoninnerlength")
        final AbstractMultipartVisitor visitor = new AbstractMultipartVisitor() {

            private OptionalInt expiration = OptionalInt.empty();

            @Override
            void emitField(final String name, final String value) {
                propertyValues.addPropertyValue(name, value);

                if ("expirationDays".equals(name)) {
                    expiration = OptionalInt.of(Integer.parseInt(value));
                }
            }

            @Override
            void emitFile(final String fileName, final InputStream inStream) {
                final Integer expirationDays = expiration
                    .orElseThrow(() -> new IllegalStateException("No expirationDays configured"));

                tmpFiles.add(messageService.encryptFile(fileName, inStream, encryptionKey,
                    Instant.now().plus(expirationDays, ChronoUnit.DAYS)));
            }

        };

        try {
            visitor.processRequest(req);
            binder.bind(propertyValues);
            binder.validate();
        } catch (final IllegalStateException ise) {
            errors.reject(null, ise.getMessage());
        }

        return tmpFiles;
    }

    /**
     * Displays the sent message to the sender after sending.
     */
    @GetMapping("/{id:[a-f0-9]{64}}")
    public String created(@PathVariable("id") final String id,
        @RequestParam("linkSecret") final String linkSecret,
                          final Model model,
                          final UriComponentsBuilder uriComponentsBuilder) {
        final SenderMessage senderMessage = messageService.getSenderMessage(id);

        final String receiveUrl = MvcUriComponentsBuilder
            .fromMappingName(uriComponentsBuilder, "RC#receive")
            .arg(0, senderMessage.getReceiverId())
            .arg(1, linkSecret)
            .build();

        model
            .addAttribute("receiveUrl", receiveUrl)
            .addAttribute("senderMessage", senderMessage)
            .addAttribute("linkSecret", linkSecret);
        return FORM_MSG_STATUS;
    }

    /**
     * Handle burn request sent by the sender.
     */
    @DeleteMapping("/{id:[a-f0-9]{64}}")
    public String burn(@PathVariable("id") final String id,
        @RequestParam("linkSecret") final String linkSecret,
                       final RedirectAttributes redirectAttributes) {

        final SenderMessage senderMessage = messageService.getSenderMessage(id);

        if (senderMessage.getReceived() != null) {
            redirectAttributes.addFlashAttribute("alreadyReceived", true);
        } else if (senderMessage.getBurned() != null) {
            redirectAttributes.addFlashAttribute("alreadyBurned", true);
        } else if (senderMessage.getInvalidated() != null) {
            redirectAttributes.addFlashAttribute("alreadyInvalidated", true);
        } else {
            messageService.burnSenderMessage(senderMessage);
            redirectAttributes.addFlashAttribute("messageBurned", true);
        }

        return String.format("redirect:/send/%s?linkSecret=%s", id, linkSecret);
    }

    private abstract class AbstractMultipartVisitor {

        abstract void emitField(String name, String value);

        abstract void emitFile(String fileName, InputStream inStream);

        final void processRequest(final HttpServletRequest req)
            throws FileUploadException, IOException {

            final ServletFileUpload upload = new ServletFileUpload();
            upload.setHeaderEncoding("UTF-8");
            upload.setSizeMax(config.getMaxRequestSize());
            upload.setFileSizeMax(config.getMaxFileSize());

            final FileItemIterator iter;
            try {
                iter = upload.getItemIterator(req);
            } catch (final FileUploadBase.SizeLimitExceededException e) {
                throw new IllegalStateException(
                    String.format("Message (including files) exceeds maximum size of %s",
                        FileUtils.byteCountToDisplaySize(config.getMaxRequestSize())));
            }


            while (iter.hasNext()) {
                final FileItemStream item = iter.next();
                final String name = item.getFieldName();

                try (final InputStream stream = item.openStream()) {
                    if (item.isFormField()) {
                        final String propertyValue = Streams.asString(stream, "UTF-8");

                        emitField(name, propertyValue);

                    } else {

                        final String filename = FilenameUtils.getName(item.getName());
                        if (Strings.isNullOrEmpty(filename)) {
                            // browser sends dummy file in case no file part is used
                            continue;
                        }
                        try {
                            emitFile(filename, stream);
                        } catch (final UncheckedIOException e) {
                            if (!(e.getCause() instanceof FileUploadBase.FileUploadIOException)) {
                                throw e;
                            }
                            throw new IllegalStateException(
                                String.format("File %s exceeded size limit of %s", filename,
                                    FileUtils.byteCountToDisplaySize(config.getMaxFileSize())));
                        }
                    }
                }
            }

        }

    }

}
